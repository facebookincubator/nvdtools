DROP TABLE IF EXISTS
	`snooze`,
	`custom_data`,
	`vendor_data`,
	`vendor`
;

SET sql_mode = '';

CREATE TABLE `vendor` (
	`version`  INT         NOT NULL AUTO_INCREMENT COMMENT 'ID of the dataset',
	`ts`       TIMESTAMP   NOT NULL  COMMENT 'Time of the dataset import',
	`ready`    BOOL        NOT NULL  COMMENT 'Indicates the dataset is ready to use',
	`owner`    VARCHAR(64) NOT NULL  COMMENT 'Point of contact for dataset',
	`provider` VARCHAR(64) NOT NULL  COMMENT 'Short name of dataset provider',
	PRIMARY KEY (`version`),
	KEY (`provider`)
)
ENGINE InnoDB
DEFAULT CHARACTER SET utf8mb4
COMMENT 'Vendors providing vulnerability datasets'
;

CREATE TABLE `vendor_data` (
	`version`    INT          NOT NULL COMMENT 'ID of the vendor dataset',
	`cve_id`     VARCHAR(128) NOT NULL COMMENT 'Common Vulnerability and Exposure (CVE) ID',
	`published`  TIMESTAMP    NOT NULL COMMENT 'Timestamp of vulnerability publication' DEFAULT CURRENT_TIMESTAMP,
	`modified`   TIMESTAMP    NOT NULL COMMENT 'Timestamp of vulnerability last modification' DEFAULT CURRENT_TIMESTAMP,
	`base_score` FLOAT(3,1)   NOT NULL COMMENT 'Base score from CVSS 3.0 or 2.0 fallback',
	`summary`    TEXT         NOT NULL COMMENT 'Description of the vulnerability',
	`cve_json`   MEDIUMBLOB   NOT NULL COMMENT 'JSON record containing raw CVE data',
	PRIMARY KEY (`version`, `cve_id`)
)
ENGINE InnoDB
DEFAULT CHARACTER SET utf8mb4
COMMENT 'Vulnerability data from vendors'
;

CREATE TABLE `custom_data` (
	`owner`       VARCHAR(64)  NOT NULL COMMENT 'Point of contact for dataset',
	`provider`    VARCHAR(64)  NOT NULL COMMENT 'Short name of data provider',
	`cve_id`      VARCHAR(128) NOT NULL COMMENT 'Common Vulnerability and Exposure ID',
	`published`   TIMESTAMP    NOT NULL COMMENT 'Timestamp of vulnerability publication' DEFAULT CURRENT_TIMESTAMP,
	`modified`    TIMESTAMP    NOT NULL COMMENT 'Timestamp of customized last modification' DEFAULT CURRENT_TIMESTAMP,
	`base_score`  FLOAT(3,1)   NOT NULL COMMENT 'Base score from CVSS 3.0 or 2.0 fallback',
	`summary`     TEXT         NOT NULL COMMENT 'Description of the vulnerability',
	`cve_json`    MEDIUMBLOB   NOT NULL COMMENT 'JSON record containing raw CVE data',
	PRIMARY KEY (`cve_id`)
)
ENGINE InnoDB
DEFAULT CHARACTER SET utf8mb4
COMMENT 'Custom vulnerability data including overrides'
;

CREATE TABLE `snooze` (
	`owner`     VARCHAR(64)  NOT NULL COMMENT 'Point of contact for snooze',
	`collector` varchar(64)  NOT NULL COMMENT 'Unique name of the data collector',
	`provider`  VARCHAR(32)  NOT NULL COMMENT 'Short name of data provider',
	`cve_id`    VARCHAR(128) NOT NULL COMMENT 'Common Vulnerability and Exposure ID',
	`deadline`  TIMESTAMP        NULL COMMENT 'Timestamp of snooze expiration' DEFAULT CURRENT_TIMESTAMP,
	`metadata`  BLOB             NULL COMMENT 'Opaque metadata for snooze management',
	PRIMARY KEY (`provider`, `cve_id`)
)
ENGINE InnoDB
DEFAULT CHARACTER SET utf8mb4
COMMENT 'Vulnerability records to ignore for a period of time'
;
