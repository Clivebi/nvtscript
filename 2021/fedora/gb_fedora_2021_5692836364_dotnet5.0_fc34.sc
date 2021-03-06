if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817768" );
	script_version( "2021-09-03T08:47:21+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:47:21 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-26 03:11:02 +0000 (Thu, 26 Aug 2021)" );
	script_name( "Fedora: Security Advisory for dotnet5.0 (FEDORA-2021-5692836364)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-5692836364" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NMGUHKLEKVAHI2NCQKNX432EAPVBUJVX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dotnet5.0'
  package(s) announced via the FEDORA-2021-5692836364 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: ".NET is a fast, lightweight and modular platform for creating
cross platform applications that work on Linux, macOS and Windows.

It particularly focuses on creating console applications, web
applications and micro-services.

.NET contains a runtime conforming to .NET Standards a set of
framework libraries, an SDK containing compilers and a &#39, dotnet&#39,
application to drive everything." );
	script_tag( name: "affected", value: "'dotnet5.0' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "dotnet5.0", rpm: "dotnet5.0~5.0.206~1.fc34", rls: "FC34" ) )){
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

