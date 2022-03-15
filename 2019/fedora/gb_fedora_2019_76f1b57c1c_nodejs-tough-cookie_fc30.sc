if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876485" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2017-15010" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-12 17:29:00 +0000 (Wed, 12 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-13 02:13:14 +0000 (Thu, 13 Jun 2019)" );
	script_name( "Fedora Update for nodejs-tough-cookie FEDORA-2019-76f1b57c1c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-76f1b57c1c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6VEBDTGNHVM677SLZDEHMWOP3ISMZSFT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs-tough-cookie'
  package(s) announced via the FEDORA-2019-76f1b57c1c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "RFC6265 Cookies and Cookie Jar for Node.js." );
	script_tag( name: "affected", value: "'nodejs-tough-cookie' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs-tough-cookie", rpm: "nodejs-tough-cookie~2.3.4~1.fc30", rls: "FC30" ) )){
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

