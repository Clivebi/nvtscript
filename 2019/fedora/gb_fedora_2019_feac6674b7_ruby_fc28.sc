if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876346" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325" );
	script_tag( name: "cvss_base", value: "8.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-16 15:15:00 +0000 (Sun, 16 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-10 02:11:44 +0000 (Fri, 10 May 2019)" );
	script_name( "Fedora Update for ruby FEDORA-2019-feac6674b7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-feac6674b7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WUFHAULLX3OK2O3CMJLJL6KKISCNX3J5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'ruby' package(s) announced via the FEDORA-2019-feac6674b7 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Ruby is the interpreted scripting language
  for quick and easy object-oriented programming.  It has many features to process
  text files and to do system management tasks (as in Perl).  It is simple,
  straight-forward, and extensible." );
	script_tag( name: "affected", value: "'ruby' package(s) on Fedora 28." );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~2.5.5~108.fc28", rls: "FC28" ) )){
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

