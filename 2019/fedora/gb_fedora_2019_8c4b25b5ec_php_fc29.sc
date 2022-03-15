if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876474" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-11040", "CVE-2019-11038", "CVE-2019-11039", "CVE-2018-19935" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 12:57:00 +0000 (Fri, 16 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-09 02:09:36 +0000 (Sun, 09 Jun 2019)" );
	script_name( "Fedora Update for php FEDORA-2019-8c4b25b5ec" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-8c4b25b5ec" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WAZBVK6XNYEIN7RDQXESSD63QHXPLKWL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php'
  package(s) announced via the FEDORA-2019-8c4b25b5ec advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated web pages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts.

The php package contains the module (often referred to as mod_php)
which adds support for the PHP language to Apache HTTP Server." );
	script_tag( name: "affected", value: "'php' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "php", rpm: "php~7.2.19~2.fc29", rls: "FC29" ) )){
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
