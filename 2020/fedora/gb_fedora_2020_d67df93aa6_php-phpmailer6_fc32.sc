if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877948" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2020-13625" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 20:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-06-08 03:33:42 +0000 (Mon, 08 Jun 2020)" );
	script_name( "Fedora: Security Advisory for php-phpmailer6 (FEDORA-2020-d67df93aa6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-d67df93aa6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WXI4BTLWBPZVP46H7IX3JQ35E2DRAG43" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2020-d67df93aa6 advisory." );
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
	script_tag( name: "affected", value: "'php-phpmailer6' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "php-phpmailer6", rpm: "php-phpmailer6~6.1.6~2.fc32", rls: "FC32" ) )){
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

