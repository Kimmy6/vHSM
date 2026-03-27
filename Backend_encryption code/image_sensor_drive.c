// image_sensor_drive.c
// Raspberry Pi + IMX219: capture one RAW10 frame via V4L2, bilinear demosaic, save as JPEG.
// Build: gcc -O2 -std=c11 image_sensor_drive.c -o image_sensor_drive -ljpeg
// Usage: ./image_sensor_drive /dev/videoX width height out.jpg [-p RGGB|BGGR|GRBG|GBRG] [-q 1..100]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <linux/videodev2.h>
#include <jpeglib.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

typedef struct { void *start; size_t length; } Buffer;
typedef enum { BAYER_RGGB=0, BAYER_BGGR=1, BAYER_GRBG=2, BAYER_GBRG=3 } BayerPattern;

static int xioctl(int fd, int req, void *arg) {
    int r;
    do { r = ioctl(fd, req, arg); } while (r == -1 && errno == EINTR);
    return r;
}

static BayerPattern parse_bayer(const char *s, bool *ok) {
    if (ok) *ok = true;
    if (!s) { if (ok) *ok=false; return BAYER_RGGB; }
    if (!strcasecmp(s,"RGGB")) return BAYER_RGGB;
    if (!strcasecmp(s,"BGGR")) return BAYER_BGGR;
    if (!strcasecmp(s,"GRBG")) return BAYER_GRBG;
    if (!strcasecmp(s,"GBRG")) return BAYER_GBRG;
    if (ok) *ok=false;
    return BAYER_RGGB;
}

static BayerPattern infer_bayer_from_fourcc(uint32_t fcc){
    switch (fcc){
        // packed 10-bit
        case V4L2_PIX_FMT_SRGGB10P: return BAYER_RGGB; // 'pRAA'
        case V4L2_PIX_FMT_SBGGR10P: return BAYER_BGGR; // 'pBAA'
        case V4L2_PIX_FMT_SGRBG10P: return BAYER_GRBG; // 'pgAA'
        case V4L2_PIX_FMT_SGBRG10P: return BAYER_GBRG; // 'pGAA'
        // 10-bit in 16-bit container
        case V4L2_PIX_FMT_SRGGB10:  return BAYER_RGGB;
        case V4L2_PIX_FMT_SBGGR10:  return BAYER_BGGR;
        case V4L2_PIX_FMT_SGRBG10:  return BAYER_GRBG;
        case V4L2_PIX_FMT_SGBRG10:  return BAYER_GBRG;
        default: return BAYER_RGGB;
    }
}

// ---------- Unpackers ----------
// Packed RAW10 (MIPI) line-by-line with stride (bytesperline)
static void unpack_bayer10p_strided(const uint8_t *src, size_t src_stride,
                                    uint16_t *dst, int w, int h)
{
    size_t active = ((size_t)w * 10 + 7) / 8;  // valid bytes per line (ceil(w*10/8))
    for (int y = 0; y < h; y++) {
        const uint8_t *s = src + (size_t)y * src_stride;
        uint16_t *d = dst + (size_t)y * w;
        size_t i = 0, o = 0;
        while (i + 5 <= active && o + 4 <= (size_t)w) {
            uint8_t b0 = s[i+0], b1 = s[i+1], b2 = s[i+2], b3 = s[i+3], b4 = s[i+4];
            uint16_t p0 = (uint16_t)b0 | ((uint16_t)(b4 & 0x03) << 8);
            uint16_t p1 = (uint16_t)b1 | ((uint16_t)(b4 & 0x0C) << 6);
            uint16_t p2 = (uint16_t)b2 | ((uint16_t)(b4 & 0x30) << 4);
            uint16_t p3 = (uint16_t)b3 | ((uint16_t)(b4 & 0xC0) << 2);
            d[o+0] = (uint16_t)(p0 << 6);
            d[o+1] = (uint16_t)(p1 << 6);
            d[o+2] = (uint16_t)(p2 << 6);
            d[o+3] = (uint16_t)(p3 << 6);
            i += 5; o += 4;
        }
        for (; o < (size_t)w; ++o) d[o] = 0; // pad tail safely
    }
}

// 10-bit in 16-bit container: copy line-by-line using stride
static void copy_16in10_strided(const uint8_t *src, size_t src_stride,
                                uint16_t *dst, int w, int h)
{
    for (int y = 0; y < h; y++) {
        const uint16_t *line = (const uint16_t *)(src + (size_t)y * src_stride);
        memcpy(&dst[(size_t)y * w], line, (size_t)w * 2);
    }
}

// If driver right-aligned the 10-bit into low bits, normalize to 16b range
static void normalize_16in10_to_16(uint16_t *buf, size_t pixels){
    size_t n = pixels < 4096 ? pixels : 4096;
    size_t right=0, left=0;
    for(size_t i=0;i<n;i++){ uint16_t v=buf[i]; if((v & 0x003F)==0) left++; if(v<=1023) right++; }
    if(right>left){ for(size_t i=0;i<pixels;i++) buf[i] <<= 6; }
}

// ---------- Demosaic ----------
static inline uint16_t P(const uint16_t *raw,int w,int h,int x,int y){
    if(x<0)x=0; else if(x>=w)x=w-1;
    if(y<0)y=0; else if(y>=h)y=h-1;
    return raw[(size_t)y*w+x];
}
static inline uint8_t to8(uint32_t v){ return (uint8_t)((v+128)>>8); }

static void demosaic_bilinear(const uint16_t *raw,int w,int h,BayerPattern pat,uint8_t *rgb){
    int ry=0, rx=0;
    switch(pat){
        case BAYER_RGGB: ry=0; rx=0; break;
        case BAYER_BGGR: ry=1; rx=1; break;
        case BAYER_GRBG: ry=0; rx=1; break;
        case BAYER_GBRG: ry=1; rx=0; break;
    }
    for(int y=0;y<h;y++){
        for(int x=0;x<w;x++){
            int yp=y&1, xp=x&1;
            bool isR=(yp==ry)&&(xp==rx);
            bool isB=(yp!=ry)&&(xp!=rx);
            uint32_t R,G,B, c=P(raw,w,h,x,y);
            if(isR){
                R=c;
                G=(P(raw,w,h,x-1,y)+P(raw,w,h,x+1,y)+P(raw,w,h,x,y-1)+P(raw,w,h,x,y+1))/4;
                B=(P(raw,w,h,x-1,y-1)+P(raw,w,h,x+1,y-1)+P(raw,w,h,x-1,y+1)+P(raw,w,h,x+1,y+1))/4;
            }else if(isB){
                B=c;
                G=(P(raw,w,h,x-1,y)+P(raw,w,h,x+1,y)+P(raw,w,h,x,y-1)+P(raw,w,h,x,y+1))/4;
                R=(P(raw,w,h,x-1,y-1)+P(raw,w,h,x+1,y-1)+P(raw,w,h,x-1,y+1)+P(raw,w,h,x+1,y+1))/4;
            }else{ // Green
                G=c;
                bool rrow=(yp==ry);
                if(rrow){
                    R=(P(raw,w,h,x-1,y)+P(raw,w,h,x+1,y))/2;
                    B=(P(raw,w,h,x,y-1)+P(raw,w,h,x,y+1))/2;
                }else{
                    R=(P(raw,w,h,x,y-1)+P(raw,w,h,x,y+1))/2;
                    B=(P(raw,w,h,x-1,y)+P(raw,w,h,x+1,y))/2; // fixed: include y
                }
            }
            size_t i=((size_t)y*w+x)*3;
            rgb[i+0]=to8(R); rgb[i+1]=to8(G); rgb[i+2]=to8(B);
        }
    }
}

// ---------- JPEG ----------
static int save_jpeg(const char *path, const uint8_t *rgb, int w, int h, int quality){
    FILE *f=fopen(path,"wb"); if(!f){ perror("fopen JPEG"); return -1; }
    struct jpeg_compress_struct cinfo; struct jpeg_error_mgr jerr;
    cinfo.err=jpeg_std_error(&jerr); jpeg_create_compress(&cinfo); jpeg_stdio_dest(&cinfo,f);
    cinfo.image_width=w; cinfo.image_height=h; cinfo.input_components=3; cinfo.in_color_space=JCS_RGB;
    jpeg_set_defaults(&cinfo);
    if(quality<1)quality=1; if(quality>100)quality=100;
    jpeg_set_quality(&cinfo, quality, TRUE);
    jpeg_start_compress(&cinfo, TRUE);
    while(cinfo.next_scanline<cinfo.image_height){
        JSAMPROW row=(JSAMPROW)&rgb[(size_t)cinfo.next_scanline*w*3];
        jpeg_write_scanlines(&cinfo, &row, 1);
    }
    jpeg_finish_compress(&cinfo); jpeg_destroy_compress(&cinfo); fclose(f); return 0;
}

// ---------- Main ----------
int main(int argc, char **argv){
    if(argc<5){
        fprintf(stderr,"Usage: %s /dev/videoX width height out.jpg [-p RGGB|BGGR|GRBG|GBRG] [-q quality]\n", argv[0]);
        return 1;
    }
    const char *dev=argv[1];
    int width=atoi(argv[2]), height=atoi(argv[3]);
    const char *jpg_path=argv[4];
    const char *pat_str=NULL; int quality=90;
    for(int i=5;i<argc;i++){
        if (i+1<argc && !strcmp(argv[i],"-p")) pat_str=argv[++i];
        else if (i+1<argc && !strcmp(argv[i],"-q")) quality=atoi(argv[++i]);
    }
    bool user_pat_ok=false;
    BayerPattern pat=parse_bayer(pat_str,&user_pat_ok);

    int fd=open(dev,O_RDWR|O_NONBLOCK,0);
    if(fd<0){ perror("open"); return 1; }

    // Try several RAW10 formats (packed first)
    uint32_t try_fmts[] = {
        V4L2_PIX_FMT_SBGGR10P, V4L2_PIX_FMT_SRGGB10P, V4L2_PIX_FMT_SGRBG10P, V4L2_PIX_FMT_SGBRG10P,
        V4L2_PIX_FMT_SBGGR10,  V4L2_PIX_FMT_SRGGB10,  V4L2_PIX_FMT_SGRBG10,  V4L2_PIX_FMT_SGBRG10
    };

    struct v4l2_format fmt={0};
    fmt.type=V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width=width;
    fmt.fmt.pix.height=height;
    fmt.fmt.pix.field=V4L2_FIELD_NONE;

    int ok=0;
    for (size_t i=0;i<sizeof(try_fmts)/sizeof(try_fmts[0]); ++i){
        fmt.fmt.pix.pixelformat = try_fmts[i];
        if (xioctl(fd, VIDIOC_S_FMT, &fmt)==0){ ok=1; break; }
    }
    if(!ok){ perror("VIDIOC_S_FMT (no RAW10)"); close(fd); return 1; }

    if(xioctl(fd, VIDIOC_G_FMT, &fmt)==-1){ perror("VIDIOC_G_FMT"); close(fd); return 1; }
    uint32_t fourcc = fmt.fmt.pix.pixelformat;
    size_t bytes_per_line = fmt.fmt.pix.bytesperline;
    size_t sizeimage      = fmt.fmt.pix.sizeimage;

    if((int)fmt.fmt.pix.width!=width || (int)fmt.fmt.pix.height!=height){
        fprintf(stderr,"[!] Driver adjusted size to %ux%u. Proceeding.\n",
                fmt.fmt.pix.width, fmt.fmt.pix.height);
        width=fmt.fmt.pix.width; height=fmt.fmt.pix.height;
    }

    // If user didn't specify CFA, infer from FourCC
    if(!user_pat_ok){
        pat = infer_bayer_from_fourcc(fourcc);
    }

    fprintf(stderr,"[i] FourCC=%.4s, bpl=%zu, size=%zu, WxH=%dx%d, JPEGq=%d, CFA=%s\n",
            (char*)&fourcc, bytes_per_line, sizeimage, width, height, quality,
            (pat==BAYER_RGGB?"RGGB":pat==BAYER_BGGR?"BGGR":pat==BAYER_GRBG?"GRBG":"GBRG"));

    // Request and mmap buffers
    struct v4l2_requestbuffers req={0};
    req.count=4; req.type=V4L2_BUF_TYPE_VIDEO_CAPTURE; req.memory=V4L2_MEMORY_MMAP;
    if(xioctl(fd, VIDIOC_REQBUFS,&req)==-1){ perror("VIDIOC_REQBUFS"); close(fd); return 1; }
    if(req.count<2){ fprintf(stderr,"Insufficient buffers\n"); close(fd); return 1; }

    Buffer bufs[8]={0};
    for(unsigned i=0;i<req.count;i++){
        struct v4l2_buffer bq={0};
        bq.type=req.type; bq.memory=V4L2_MEMORY_MMAP; bq.index=i;
        if(xioctl(fd, VIDIOC_QUERYBUF,&bq)==-1){ perror("VIDIOC_QUERYBUF"); close(fd); return 1; }
        bufs[i].length=bq.length;
        bufs[i].start=mmap(NULL,bq.length,PROT_READ|PROT_WRITE,MAP_SHARED,fd,bq.m.offset);
        if(bufs[i].start==MAP_FAILED){ perror("mmap"); close(fd); return 1; }
        if(xioctl(fd, VIDIOC_QBUF,&bq)==-1){ perror("VIDIOC_QBUF"); close(fd); return 1; }
    }

    enum v4l2_buf_type type=req.type;
    if(xioctl(fd, VIDIOC_STREAMON,&type)==-1){ perror("VIDIOC_STREAMON"); close(fd); return 1; }

    // Grab one frame (skip a couple optionally)
    struct v4l2_buffer b={0}; b.type=req.type; b.memory=V4L2_MEMORY_MMAP;
    fd_set fds; FD_ZERO(&fds); FD_SET(fd,&fds);
    struct timeval tv={.tv_sec=2,.tv_usec=0};
    if(select(fd+1,&fds,NULL,NULL,&tv)<=0){ fprintf(stderr,"select timeout/error\n"); }
    if(xioctl(fd, VIDIOC_DQBUF,&b)==-1){ perror("VIDIOC_DQBUF"); }

    const uint8_t *frame=(const uint8_t*)bufs[b.index].start;
    size_t pixels=(size_t)width*height;

    // Robust stride: if driver bpl is 0, or bytesused implies a different stride, compute it.
    size_t line_active = ((size_t)width*10 + 7)/8; // for packed
    size_t used_bpl = bytes_per_line;
    if(used_bpl==0){
        // derive from bytesused if available
        if(b.bytesused && height) used_bpl = b.bytesused / (size_t)height;
        if(used_bpl<line_active) used_bpl = line_active;
    }

    uint16_t *raw16=malloc(pixels*2);
    if(!raw16){ fprintf(stderr,"OOM raw16\n"); goto done; }

    if (fourcc==V4L2_PIX_FMT_SRGGB10P || fourcc==V4L2_PIX_FMT_SBGGR10P ||
        fourcc==V4L2_PIX_FMT_SGRBG10P || fourcc==V4L2_PIX_FMT_SGBRG10P)
    {
        unpack_bayer10p_strided(frame, used_bpl?used_bpl:bytes_per_line, raw16, width, height);
    }
    else if (fourcc==V4L2_PIX_FMT_SRGGB10 || fourcc==V4L2_PIX_FMT_SBGGR10 ||
             fourcc==V4L2_PIX_FMT_SGRBG10 || fourcc==V4L2_PIX_FMT_SGBRG10)
    {
        copy_16in10_strided(frame, bytes_per_line?bytes_per_line:(size_t)width*2, raw16, width, height);
        normalize_16in10_to_16(raw16, pixels);
    }
    else{
        fprintf(stderr,"[!] Unsupported FourCC %.4s\n",(char*)&fourcc);
        free(raw16); goto done;
    }

    uint8_t *rgb=malloc(pixels*3);
    if(!rgb){ fprintf(stderr,"OOM rgb\n"); free(raw16); goto done; }
    demosaic_bilinear(raw16,width,height,pat,rgb);

    if(save_jpeg(jpg_path,rgb,width,height,quality)==0)
        fprintf(stderr,"[i] Saved JPEG: %s\n",jpg_path);

    free(rgb); free(raw16);

done:
    if(b.length) xioctl(fd, VIDIOC_QBUF,&b);
    xioctl(fd, VIDIOC_STREAMOFF,&type);
    for(unsigned i=0;i<req.count;i++) if(bufs[i].start) munmap(bufs[i].start,bufs[i].length);
    close(fd);
    return 0;
}
