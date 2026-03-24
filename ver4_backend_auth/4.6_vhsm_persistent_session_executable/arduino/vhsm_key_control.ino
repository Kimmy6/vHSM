constexpr int PIN_KEY1 = 3;
    constexpr int PIN_KEY2 = 4;
    constexpr int PIN_KEY3 = 5;

    void setAllLow() {
      digitalWrite(PIN_KEY1, LOW);
      digitalWrite(PIN_KEY2, LOW);
      digitalWrite(PIN_KEY3, LOW);
    }

    void setKeyPin(const String& keyNumber) {
      setAllLow();

      if (keyNumber == "1") {
        digitalWrite(PIN_KEY1, HIGH);
      } else if (keyNumber == "2") {
        digitalWrite(PIN_KEY2, HIGH);
      } else if (keyNumber == "3") {
        digitalWrite(PIN_KEY3, HIGH);
      }
    }

    String readLine() {
      static String buffer;
      while (Serial.available() > 0) {
        char c = static_cast<char>(Serial.read());
        if (c == '
') {
          String line = buffer;
          buffer = "";
          line.trim();
          return line;
        }
        if (c != '') {
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

      const String mode = line.substring(4, firstSep);
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
      Serial.println("OK");
    }
