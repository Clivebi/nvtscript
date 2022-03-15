if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875520" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-12895" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-20 15:44:00 +0000 (Mon, 20 Aug 2018)" );
	script_tag( name: "creation_date", value: "2019-03-28 13:54:13 +0000 (Thu, 28 Mar 2019)" );
	script_name( "Fedora Update for wordpress FEDORA-2019-8606c6da35" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-8606c6da35" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PNYBBUKLMVODGL4PQO65HH4GNZJ5MUFB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wordpress'
  package(s) announced via the FEDORA-2019-8606c6da35 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Wordpress is an online publishing / weblog
  package that makes it very easy, almost trivial, to get information out to
  people on the web.

Important information in /usr/share/doc/wordpress/README.fedora" );
	script_tag( name: "affected", value: "'wordpress' package(s) on Fedora 28." );
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
	if(!isnull( res = isrpmvuln( pkg: "wordpress", rpm: "wordpress~5.1.1~1.fc28", rls: "FC28" ) )){
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

