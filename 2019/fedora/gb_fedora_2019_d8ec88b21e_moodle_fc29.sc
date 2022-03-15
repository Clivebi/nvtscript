if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876221" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-3810", "CVE-2019-3809", "CVE-2019-3808" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:39:37 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for moodle FEDORA-2019-d8ec88b21e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-d8ec88b21e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AWFAQ4UBFJMHBKY5ZOHPH2BGQLQBFNPS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'moodle'
  package(s) announced via the FEDORA-2019-d8ec88b21e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Moodle is a course management system (CMS) - a free, Open Source software
package designed using sound pedagogical principles, to help educators create
effective online learning communities." );
	script_tag( name: "affected", value: "'moodle' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "moodle", rpm: "moodle~3.5.4~1.fc29", rls: "FC29" ) )){
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

