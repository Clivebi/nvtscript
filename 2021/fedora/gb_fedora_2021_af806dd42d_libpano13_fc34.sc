if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879470" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2021-20307" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-25 03:09:53 +0000 (Sun, 25 Apr 2021)" );
	script_name( "Fedora: Security Advisory for libpano13 (FEDORA-2021-af806dd42d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-af806dd42d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FVJRXUOBN56ZWP6QQ3NTA6DIFZMDZAEQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpano13'
  package(s) announced via the FEDORA-2021-af806dd42d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Helmut Dersch&#39, s Panorama Tools library.  Provides very high quality
manipulation, correction and stitching of panoramic photographs.

Due to patent restrictions, this library has a maximum fisheye field-of-view
restriction of 179 degrees to prevent stitching of hemispherical photographs." );
	script_tag( name: "affected", value: "'libpano13' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpano13", rpm: "libpano13~2.9.20~1.fc34", rls: "FC34" ) )){
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

