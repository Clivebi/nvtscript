if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869823" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-30 05:08:41 +0200 (Thu, 30 Jul 2015)" );
	script_cve_id( "CVE-2015-1863" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for wpa_supplicant FEDORA-2015-11691" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wpa_supplicant'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "wpa_supplicant on Fedora 21" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-11691" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162684.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC21" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC21"){
	if(( res = isrpmvuln( pkg: "wpa_supplicant", rpm: "wpa_supplicant~2.0~14.fc21", rls: "FC21" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

