// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { manifest } from "../lib/constants/waf-constants";

describe("AWS S3 Bucket Name Validation", () => {
  const s3BucketPattern: RegExp = new RegExp(
    manifest.wafSecurityAutomations.appAccessLogBucket.patter,
  );
  const isValidBucketName = (name: string): boolean =>
    s3BucketPattern.test(name);

  test.each([
    [""], // Empty string
    ["my-bucket-name"],
    ["my.bucket.name"],
    ["mybucket123"],
    ["my-bucket"],
    ["bucket.123"],
    ["a".repeat(61) + "1"], // Max length 62 characters
    ["abc"],
    ["123bucket"],
  ])("should validate correct bucket name: %s", (bucketName) => {
    expect(isValidBucketName(bucketName)).toBeTruthy();
  });

  test.each([
    ["A-UPPERCASE"], // Contains uppercase
    ["my..bucket"], // Consecutive dots
    ["my.-bucket"], // Dot followed by hyphen
    ["my-.bucket"], // Hyphen followed by dot
    [".mybucket"], // Starts with dot
    ["mybucket."], // Ends with dot
    ["-mybucket"], // Starts with hyphen
    ["mybucket-"], // Ends with hyphen
    ["192.168.1.1"], // IP address format
    ["my_bucket"], // Underscore not allowed
    ["a".repeat(64)], // Too long (>63 characters)
    ["my@bucket"], // Special characters
    ["my bucket"], // Space not allowed
  ])("should invalidate incorrect bucket name: %s", (bucketName) => {
    expect(isValidBucketName(bucketName)).toBeFalsy();
  });

  describe("Edge Cases", () => {
    test("should handle minimum length (3 characters)", () => {
      expect(isValidBucketName("abc")).toBeTruthy();
      expect(isValidBucketName("ab")).toBeFalsy();
    });

    test("should handle maximum length (63 characters)", () => {
      const maxLengthBucket = "a".repeat(61) + "1";
      const tooLongBucket = "a".repeat(64);

      expect(isValidBucketName(maxLengthBucket)).toBeTruthy();
      expect(isValidBucketName(tooLongBucket)).toBeFalsy();
    });

    test("should validate numbers at start that are not IP-like", () => {
      expect(isValidBucketName("123bucket")).toBeTruthy();
      expect(isValidBucketName("192.168.1.1")).toBeFalsy();
    });

    test("should handle single dots correctly", () => {
      expect(isValidBucketName("my.bucket")).toBeTruthy();
      expect(isValidBucketName("my..bucket")).toBeFalsy();
    });

    test("should handle single hyphens correctly", () => {
      expect(isValidBucketName("my-bucket")).toBeTruthy();
      expect(isValidBucketName("my--bucket")).toBeTruthy();
    });
  });
});

describe("RequestThresholdByCountryParam Validation", () => {
  const requestThresholdPattern: RegExp = new RegExp(
    manifest.wafSecurityAutomations.requestThresholdByCountry.patter,
  );

  const isValidRequestThreshold = (param: string): boolean =>
    requestThresholdPattern.test(param);

  test.each([
    ['{"TR":50,"ER":150}', true],
    ['{"US":100}', true],
    ['{"TR":0,"US":150,"UK":200}', true],
    ['{"CN":999}', true],
    ['{"AA":1,"BB":2,"CC":3,"DD":4}', true],
    ["", true], // Empty string is valid according to pattern
  ])(
    "should validate correct format: %s",
    (param: string, expected: boolean) => {
      expect(isValidRequestThreshold(param)).toBe(expected);
    },
  );

  test.each([
    ["{TR:50}", false], // Missing quotes around country code
    ['{"TR":50,}', false], // Trailing comma
    ['{"TR" : 50}', false], // Extra spaces
    ['{"TR":"50"}', false], // Value as string instead of number
    ['{"}', false], // Invalid JSON
    ['{"TR":50,"ER":}', false], // Missing value
    ['{"TR":50,"ER":150,}', false], // Trailing comma
    ["TR:50,ER:150", false], // Missing brackets
    ['{"TR":50;ER:150}', false], // Invalid separator
    ['{"TR":-50}', false], // Negative number
    ['{"TR":50.5}', false], // Decimal number
    ['[{"TR":50}]', false], // Array format
    ['{"TR":50}\n{"ER":150}', false], // Multiple lines
  ])(
    "should invalidate incorrect format: %s",
    (param: string, expected: boolean) => {
      expect(isValidRequestThreshold(param)).toBe(expected);
    },
  );

  describe("Edge Cases", () => {
    test("should handle multiple country codes", () => {
      const longFormat = Array.from(
        { length: 10 },
        (_, i) =>
          `"${String.fromCharCode(65 + i)}${String.fromCharCode(65 + i)}":${i + 1}`,
      ).join(",");

      expect(isValidRequestThreshold(`{${longFormat}}`)).toBeTruthy();
    });

    test("should handle large numbers", () => {
      expect(isValidRequestThreshold('{"TR":999999999}')).toBeTruthy();
    });

    test("should validate country code format", () => {
      expect(isValidRequestThreshold('{"T1":50}')).toBeTruthy(); // Alphanumeric is allowed by \w
      expect(isValidRequestThreshold('{"1T":50}')).toBeTruthy(); // Alphanumeric is allowed by \w
    });
  });

  describe("Real World Scenarios", () => {
    test("should handle common country configurations", () => {
      const cases = [
        '{"US":100,"UK":100,"DE":100,"FR":100,"IT":100}',
        '{"CN":500,"JP":500,"KR":500}',
        '{"BR":200,"AR":200,"CL":200,"MX":200}',
      ];

      cases.forEach((testCase) => {
        expect(isValidRequestThreshold(testCase)).toBeTruthy();
      });
    });

    test("should handle varying threshold values", () => {
      const cases = ['{"US":0}', '{"UK":1000}', '{"DE":999999}'];

      cases.forEach((testCase) => {
        expect(isValidRequestThreshold(testCase)).toBeTruthy();
      });
    });
  });
});

describe("SNSEmailParam Validation", () => {
  const snsEmailPattern: RegExp = new RegExp(
    manifest.wafSecurityAutomations.snsEmail.patter,
  );
  const isValidSNSEmail = (email: string): boolean =>
    snsEmailPattern.test(email);

  test.each([
    ["user@example.com"],
    ["user.name@example.com"],
    ["user+label@example.com"],
    ["user123@example.co.uk"],
    ["first.last@subdomain.example.com"],
    ["user-name@domain.com"],
    ["u@domain.com"],
    ["very.common@example.com"],
    ["disposable.style.email.with+symbol@example.com"],
    ["other.email-with-hyphen@example.com"],
    ["fully-qualified-domain@example.com"],
    ["user.name+tag+sorting@example.com"],
    ["x@example.com"],
    ["example-indeed@strange-example.com"],
    ["example@s.example"],
    [""], // Empty string is valid according to pattern
  ])("should validate correct email: %s", (email: string) => {
    expect(isValidSNSEmail(email)).toBeTruthy();
  });

  describe("Edge Cases", () => {
    test("should handle long email addresses", () => {
      const longLocalPart = "a".repeat(64);
      const longDomain = "b".repeat(63);

      expect(
        isValidSNSEmail(`${longLocalPart}@${longDomain}.com`),
      ).toBeTruthy();
    });

    test("should handle special characters in local part", () => {
      expect(isValidSNSEmail("user.name+tag_123@example.com")).toBeTruthy();
      expect(
        isValidSNSEmail("user!#$%&'*+-/=?^_`{|}~@example.com"),
      ).toBeFalsy();
    });

    test("should handle domain with multiple parts", () => {
      expect(isValidSNSEmail("email@sub.domain.co.uk")).toBeTruthy();
    });
  });

  describe("Real World Scenarios", () => {
    test("should validate common email providers", () => {
      const commonEmails = [
        "user@gmail.com",
        "user@yahoo.com",
        "user@outlook.com",
        "user@hotmail.com",
        "user@company.co.uk",
        "user@domain.info",
      ];

      commonEmails.forEach((email) => {
        expect(isValidSNSEmail(email)).toBeTruthy();
      });
    });

    test("should handle corporate email patterns", () => {
      const corporateEmails = [
        "firstname.lastname@company.com",
        "department-name@company.com",
        "team.lead@sub.company.com",
      ];

      corporateEmails.forEach((email) => {
        expect(isValidSNSEmail(email)).toBeTruthy();
      });
    });
  });

  describe("Length Limitations", () => {
    test("should handle minimum length requirements", () => {
      expect(isValidSNSEmail("a@b.co")).toBeTruthy();
      expect(isValidSNSEmail("a@b.c")).toBeFalsy();
    });

    test("should validate domain extension length", () => {
      expect(isValidSNSEmail("test@domain.c")).toBeFalsy();
      expect(isValidSNSEmail("test@domain.co")).toBeTruthy();
      expect(isValidSNSEmail("test@domain.info")).toBeTruthy();
    });
  });

  describe("Additional Validations", () => {
    test("should handle case sensitivity correctly", () => {
      expect(isValidSNSEmail("USER@DOMAIN.COM")).toBeTruthy();
      expect(isValidSNSEmail("user@DOMAIN.COM")).toBeTruthy();
      expect(isValidSNSEmail("User@Domain.Com")).toBeTruthy();
    });

    test("should validate empty string", () => {
      expect(isValidSNSEmail("")).toBeTruthy();
    });

    test("should handle whitespace", () => {
      expect(isValidSNSEmail(" user@domain.com")).toBeFalsy();
      expect(isValidSNSEmail("user@domain.com ")).toBeFalsy();
      expect(isValidSNSEmail("user @domain.com")).toBeFalsy();
      expect(isValidSNSEmail("user@ domain.com")).toBeFalsy();
    });
  });
});

describe("CustomHeaderName Validation", () => {
  const customHeaderPattern: RegExp = new RegExp(
    manifest.wafSecurityAutomations.customHeaderName.patter,
  );

  const isValidCustomHeader = (header: string): boolean =>
    customHeaderPattern.test(header);

  test.each([
    [""], // Empty string
    ["X-Custom-Header"], // Standard custom header
    ["x-custom-header"], // Lowercase
    ["X_CUSTOM_HEADER"], // Uppercase with underscores
    ["X-Custom-Header-123"], // With numbers
    ["CustomHeader"], // Without hyphens
    ["Header1"], // With number
    ["X-"], // Just prefix
    ["-X"], // Just suffix
    ["123"], // Just numbers
    ["!@#"], // Special characters
    [" X "], // Spaces with non-space
    ["  X"], // Multiple leading spaces with non-space
    ["X  "], // Multiple trailing spaces with non-space
    ["X-Custom Header"], // Space in middle
  ])("should validate correct header: %s", (header: string) => {
    expect(isValidCustomHeader(header)).toBeTruthy();
  });

  test.each([
    [" "], // Single space
    ["   "], // Multiple spaces
    ["\t"], // Tab
    ["\n"], // Newline
    ["\r"], // Carriage return
    ["\r\n"], // Carriage return + newline
  ])("should invalidate incorrect header: %s", (header: string) => {
    expect(isValidCustomHeader(header)).toBeFalsy();
  });

  describe("Edge Cases", () => {
    test("should validate empty string", () => {
      expect(isValidCustomHeader("")).toBeTruthy();
    });

    test("should validate string with only whitespace characters", () => {
      expect(isValidCustomHeader(" ")).toBeFalsy();
      expect(isValidCustomHeader("  ")).toBeFalsy();
      expect(isValidCustomHeader("\t")).toBeFalsy();
      expect(isValidCustomHeader("\n")).toBeFalsy();
      expect(isValidCustomHeader("\r")).toBeFalsy();
      expect(isValidCustomHeader("\r\n")).toBeFalsy();
    });

    test("should validate string with whitespace and non-whitespace", () => {
      expect(isValidCustomHeader(" X")).toBeTruthy();
      expect(isValidCustomHeader("X ")).toBeTruthy();
      expect(isValidCustomHeader(" X ")).toBeTruthy();
      expect(isValidCustomHeader("\tX")).toBeTruthy();
      expect(isValidCustomHeader("X\t")).toBeTruthy();
      expect(isValidCustomHeader("\nX")).toBeTruthy();
      expect(isValidCustomHeader("X\n")).toBeTruthy();
    });
  });

  describe("Special Characters", () => {
    test("should validate headers with special characters", () => {
      const specialChars = ["!@#$%^&*()", "[]{}|\\", "\"'", "<>,.?/", "±§`~"];

      specialChars.forEach((char) => {
        expect(isValidCustomHeader(char)).toBeTruthy();
      });
    });
  });

  describe("Length Variations", () => {
    test("should validate headers of different lengths", () => {
      const lengths = [
        "X", // Single character
        "XX", // Two characters
        "X".repeat(10), // 10 characters
        "X".repeat(50), // 50 characters
        "X".repeat(100), // 100 characters
      ];

      lengths.forEach((header) => {
        expect(isValidCustomHeader(header)).toBeTruthy();
      });
    });
  });

  describe("Common Header Patterns", () => {
    test("should validate common header formats", () => {
      const commonPatterns = [
        "X-Custom-Header",
        "X-API-Key",
        "X-Request-ID",
        "X-Correlation-ID",
        "X-Forwarded-For",
        "X-Real-IP",
        "Custom-Header",
        "API-Version",
        "Request-Timeout",
        "Authorization-Token",
      ];

      commonPatterns.forEach((header) => {
        expect(isValidCustomHeader(header)).toBeTruthy();
      });
    });
  });

  describe("Whitespace Combinations", () => {
    test("should handle various whitespace combinations correctly", () => {
      const validWhitespace = [
        " X",
        "X ",
        " X ",
        "  X  ",
        "\tX\t",
        "\nX\n",
        " X\t",
        "\tX ",
        "X Y",
        "X  Y",
        "X\tY",
        "X\nY",
      ];

      const invalidWhitespace = [
        " ",
        "  ",
        "\t",
        "\n",
        "\t\t",
        "\n\n",
        " \t",
        "\t ",
        " \n",
        "\n ",
      ];

      validWhitespace.forEach((header) => {
        expect(isValidCustomHeader(header)).toBeTruthy();
      });

      invalidWhitespace.forEach((header) => {
        expect(isValidCustomHeader(header)).toBeFalsy();
      });
    });
  });
});
