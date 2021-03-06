if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810156" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-02 14:03:25 +0100 (Fri, 02 Dec 2016)" );
	script_cve_id( "CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5192", "CVE-2016-5189", "CVE-2016-5186", "CVE-2016-5191", "CVE-2016-5190", "CVE-2016-5193", "CVE-2016-5194", "CVE-2016-5198" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for chromium-native_client FEDORA-2016-c671aae490" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium-native_client'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "chromium-native_client on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-c671aae490" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DISCLNR37PIQKLLY5LUXN33SJ5EGY7JV" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "chromium-native_client", rpm: "chromium-native_client~54.0.2840.59~1.20161013git090f907.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

