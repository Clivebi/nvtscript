if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875568" );
	script_version( "2019-04-22T07:09:02+0000" );
	script_cve_id( "CVE-2019-1002162" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-04-22 07:09:02 +0000 (Mon, 22 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-19 02:07:35 +0000 (Fri, 19 Apr 2019)" );
	script_name( "Fedora Update for atomic-reactor FEDORA-2019-782e6e61ce" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-782e6e61ce" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZWONUGHTGT6T2K5N66SYDVF5U5QQ26YE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'atomic-reactor'
  package(s) announced via the FEDORA-2019-782e6e61ce advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simple Python tool with command line interface for building Docker
images. It contains a lot of helpful functions which you would
probably implement if you started hooking Docker into your
infrastructure." );
	script_tag( name: "affected", value: "'atomic-reactor' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "atomic-reactor", rpm: "atomic-reactor~1.6.36.1~3.fc28", rls: "FC28" ) )){
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

