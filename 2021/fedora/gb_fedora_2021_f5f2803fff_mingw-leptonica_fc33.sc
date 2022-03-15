if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879410" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-36281", "CVE-2020-36277", "CVE-2020-36278", "CVE-2020-36279", "CVE-2020-36280" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-22 12:58:00 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-23 03:16:26 +0000 (Fri, 23 Apr 2021)" );
	script_name( "Fedora: Security Advisory for mingw-leptonica (FEDORA-2021-f5f2803fff)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-f5f2803fff" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ER5AGIFTFWW5A2YB5TZUCUBYQT2V2CIP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-leptonica'
  package(s) announced via the FEDORA-2021-f5f2803fff advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows Leptonica library." );
	script_tag( name: "affected", value: "'mingw-leptonica' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-leptonica", rpm: "mingw-leptonica~1.80.0~2.fc33", rls: "FC33" ) )){
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

