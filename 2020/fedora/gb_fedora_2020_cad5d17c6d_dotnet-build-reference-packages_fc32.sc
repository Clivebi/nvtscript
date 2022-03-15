if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878296" );
	script_version( "2021-07-13T11:00:50+0000" );
	script_cve_id( "CVE-2020-1597" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 11:00:50 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-25 20:15:00 +0000 (Fri, 25 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-13 03:07:24 +0000 (Sun, 13 Sep 2020)" );
	script_name( "Fedora: Security Advisory for dotnet-build-reference-packages (FEDORA-2020-cad5d17c6d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-cad5d17c6d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LUGHX2CRLOXGUVN3UDAGAK3XJG4ORXFS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dotnet-build-reference-packages'
  package(s) announced via the FEDORA-2020-cad5d17c6d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This contains references packages used for building .NET Core.

This is not meant to be used by end-users." );
	script_tag( name: "affected", value: "'dotnet-build-reference-packages' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "dotnet-build-reference-packages-0", rpm: "dotnet-build-reference-packages-0~5.20200608git1b1a695.fc32", rls: "FC32" ) )){
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

