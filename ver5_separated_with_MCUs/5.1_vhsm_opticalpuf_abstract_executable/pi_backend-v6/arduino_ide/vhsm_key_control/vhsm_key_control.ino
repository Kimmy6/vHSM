constexpr int PIN_KEY1 = 3;
constexpr int PIN_KEY2 = 4;
constexpr int PIN_KEY3 = 5;

constexpr unsigned long KEY_ON_DURATION_MS = 3000;  // 3초 ON 유지

void setAllLow() {
  digitalWrite(PIN_KEY1, LOW);
  digitalWrite(PIN_KEY2, LOW);
  digitalWrite(PIN_KEY3, LOW);
}

// 해당 핀을 3초간 HIGH → 자동 LOW (시리얼 출력 없음 — Pi가 OK 전에 읽으면 오류)
void setKeyPin(const String& keyNumber) {
  setAllLow();

  int targetPin = -1;
  if      (keyNumber == "1") targetPin = PIN_KEY1;
  else if (keyNumber == "2") targetPin = PIN_KEY2;
  else if (keyNumber == "3") targetPin = PIN_KEY3;

  if (targetPin < 0) return;

  digitalWrite(targetPin, HIGH);
  delay(KEY_ON_DURATION_MS);   // 3초 대기
  digitalWrite(targetPin, LOW);
}

String readLine() {
  static String buffer;
  while (Serial.available() > 0) {
    char c = static_cast<char>(Serial.read());
    if (c == '\n') {
      String line = buffer;
      buffer = "";
      line.trim();
      return line;
    }
    if (c != '\r') {
      buffer += c;
    }
  }
  return "";
}

void setup() {
  pinMode(PIN_KEY1, OUTPUT);
  pinMode(PIN_KEY2, OUTPUT);
  pinMode(PIN_KEY3, OUTPUT);
  setAllLow();

  Serial.begin(115200);
  while (!Serial) {
    ;
  }
  Serial.println("READY");
}

void loop() {
  const String line = readLine();
  if (line.length() == 0) {
    return;
  }

  // Expected format: KEY:<encrypt|decrypt>:<1|2|3>
  if (!line.startsWith("KEY:")) {
    Serial.println("ERROR: UNKNOWN_COMMAND");
    return;
  }

  const int firstSep = line.indexOf(':', 4);
  if (firstSep < 0) {
    Serial.println("ERROR: INVALID_FORMAT");
    return;
  }

  const String mode      = line.substring(4, firstSep);
  const String keyNumber = line.substring(firstSep + 1);

  if (!(mode == "encrypt" || mode == "decrypt")) {
    Serial.println("ERROR: INVALID_MODE");
    return;
  }

  if (!(keyNumber == "1" || keyNumber == "2" || keyNumber == "3")) {
    Serial.println("ERROR: INVALID_KEY");
    return;
  }

  setKeyPin(keyNumber);
  Serial.println("OK");   // ← 3초 뒤에 OK 전송 (Pi가 이것만 읽음)
}
