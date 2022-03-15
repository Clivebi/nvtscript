if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875294" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-10779", "CVE-2017-11613", "CVE-2017-9935", "CVE-2017-18013", "CVE-2018-8905", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-5784", "CVE-2018-18661", "CVE-2018-18557" );
	script_bugtraq_id( 106054 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-21 16:00:00 +0000 (Thu, 21 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-12-04 12:40:41 +0530 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for libtiff FEDORA-2018-399bce9f8f" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	script_xref( name: "FEDORA", value: "2018-399bce9f8f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y4XDS4ASFUN75CXGD4A6LIXCBAL3H2HN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff'
  package(s) announced via the FEDORA-2018-399bce9f8f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "libtiff on Fedora 27." );
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
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~4.0.10~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

