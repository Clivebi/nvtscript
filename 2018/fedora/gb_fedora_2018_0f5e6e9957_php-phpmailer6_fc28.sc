if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875315" );
	script_version( "2021-06-11T11:00:20+0000" );
	script_cve_id( "CVE-2018-19296" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 18:34:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-04 08:28:01 +0100 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for php-phpmailer6 FEDORA-2018-0f5e6e9957" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-0f5e6e9957" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZXE5CR2VWTH7XFU3CHRXPFVHMGA7ZJX2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2018-0f5e6e9957 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "php-phpmailer6 on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "php-phpmailer6", rpm: "php-phpmailer6~6.0.6~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

