void setup() {
  Serial.begin(9600);

  pinMode(3, OUTPUT);
  pinMode(4, OUTPUT);
  pinMode(5, OUTPUT);

  Serial.println("=== Arduino MEGA 2560 핀 제어 ===");
  Serial.println("명령어: Red | Green | Blue");
  Serial.println("================================");
}

void loop() {
  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input == "Red") {
      Serial.println("[Red 입력] → Pin 3 ON");
      digitalWrite(3, HIGH);
      delay(3000);
      digitalWrite(3, LOW);
      Serial.println("[완료]    → Pin 3 OFF");

    } else if (input == "Green") {
      Serial.println("[Green 입력] → Pin 4 ON");
      digitalWrite(4, HIGH);
      delay(3000);
      digitalWrite(4, LOW);
      Serial.println("[완료]      → Pin 4 OFF");

    } else if (input == "Blue") {
      Serial.println("[Blue 입력] → Pin 5 ON");
      digitalWrite(5, HIGH);
      delay(3000);
      digitalWrite(5, LOW);
      Serial.println("[완료]     → Pin 5 OFF");

    } else {
      Serial.print("[오류] 알 수 없는 명령어: ");
      Serial.println(input);
      Serial.println("명령어: Red | Green | Blue");
    }

    Serial.println("--------------------------------");
  }
}
