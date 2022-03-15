if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879573" );
	script_version( "2021-08-20T12:01:13+0000" );
	script_cve_id( "CVE-2020-36326", "CVE-2018-19296" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 12:01:13 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 15:17:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-13 03:24:16 +0000 (Thu, 13 May 2021)" );
	script_name( "Fedora: Security Advisory for php-phpmailer6 (FEDORA-2021-ecf4fed550)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-ecf4fed550" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3B5WDPGUFNPG4NAZ6G4BZX43BKLAVA5B" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2021-ecf4fed550 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PHPMailer - A full-featured email creation and transfer class for PHP

Class Features

  * Probably the world&#39, s most popular code for sending email from PHP!

  * Used by many open-source projects:
  WordPress, Drupal, 1CRM, SugarCRM, Yii, Joomla! and many more

  * Integrated SMTP support - send without a local mail server

  * Send emails with multiple To, CC, BCC and Reply-to addresses

  * Multipart/alternative emails for mail clients that do not read HTML email

  * Add attachments, including inline

  * Support for UTF-8 content and 8bit, base64, binary, and quoted-printable
  encodings

  * SMTP authentication with LOGIN, PLAIN, CRAM-MD5 and XOAUTH2 mechanisms
  over SSL and SMTP+STARTTLS transports

  * Validates email addresses automatically

  * Protect against header injection attacks

  * Error messages in 47 languages!

  * DKIM and S/MIME signing support

  * Compatible with PHP 5.5 and later

  * Namespaced to prevent name clashes

  * Much more!


Autoloader: /usr/share/php/PHPMailer/PHPMailer6/autoload.php" );
	script_tag( name: "affected", value: "'php-phpmailer6' package(s) on Fedora 33." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "php-phpmailer6", rpm: "php-phpmailer6~6.4.1~1.fc33", rls: "FC33" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

