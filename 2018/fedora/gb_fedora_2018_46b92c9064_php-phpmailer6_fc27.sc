if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875295" );
	script_version( "2021-06-10T02:00:20+0000" );
	script_cve_id( "CVE-2018-19296" );
	script_bugtraq_id( 106054 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-10 02:00:20 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 18:34:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-04 12:40:36 +0530 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for php-phpmailer6 FEDORA-2018-46b92c9064" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	script_xref( name: "FEDORA", value: "2018-46b92c9064" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7BVXCKTJQBY2PZGWGUFENTIDVHGQLDIV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-phpmailer6'
  package(s) announced via the FEDORA-2018-46b92c9064 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "php-phpmailer6 on Fedora 27." );
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
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "php-phpmailer6", rpm: "php-phpmailer6~6.0.6~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

