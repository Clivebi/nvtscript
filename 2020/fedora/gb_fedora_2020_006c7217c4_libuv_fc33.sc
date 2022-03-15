if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878390" );
	script_version( "2020-10-08T07:56:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-08 07:56:44 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-02 03:11:06 +0000 (Fri, 02 Oct 2020)" );
	script_name( "Fedora: Security Advisory for libuv (FEDORA-2020-006c7217c4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-006c7217c4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GRACEATF77QULUT3WY4JG54X5ZI4OUWO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libuv'
  package(s) announced via the FEDORA-2020-006c7217c4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libuv is a new platform layer for Node. Its purpose is to abstract IOCP on
Windows and libev on Unix systems. We intend to eventually contain all platform
differences in this library." );
	script_tag( name: "affected", value: "'libuv' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "libuv", rpm: "libuv~1.39.0~1.fc33", rls: "FC33" ) )){
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

