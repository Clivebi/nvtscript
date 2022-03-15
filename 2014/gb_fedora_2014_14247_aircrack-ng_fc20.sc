if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868485" );
	script_version( "2020-02-10T07:58:04+0000" );
	script_tag( name: "last_modification", value: "2020-02-10 07:58:04 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-11-14 06:45:47 +0100 (Fri, 14 Nov 2014)" );
	script_cve_id( "CVE-2014-8321", "CVE-2014-8322", "CVE-2014-8323", "CVE-2014-8324" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for aircrack-ng FEDORA-2014-14247" );
	script_tag( name: "summary", value: "Check the version of aircrack-ng" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "aircrack-ng on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-14247" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143595.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "aircrack-ng", rpm: "aircrack-ng~1.2~0.3.rc1.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
