# 1. 빌드 스테이지: Gradle을 사용하여 JAR 파일 생성
FROM gradle:8.5-jdk17 AS builder

WORKDIR /build

COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src

RUN gradle build -x test


# 2. 실행 스테이지: 빌드된 JAR만 복사하여 최종 이미지 생성
FROM openjdk:17-jdk-slim-bullseye

WORKDIR /app

# 보안을 위해 새로운 유저 생성
RUN apt-get update && apt-get install -y --no-install-recommends adduser \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring

# 빌드 스테이지에서 생성된 JAR 파일만 복사
COPY --from=builder /build/build/libs/*-SNAPSHOT.jar ./app.jar

# 포트 노출 (선택 사항, 문서화 목적)
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar", "--spring.profiles.active=prod"]


