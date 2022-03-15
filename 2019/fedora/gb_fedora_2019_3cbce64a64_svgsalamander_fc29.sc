if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876149" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2017-5617" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-08 14:38:00 +0000 (Wed, 08 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:36:46 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for svgsalamander FEDORA-2019-3cbce64a64" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-3cbce64a64" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UPUOI6NCEB6H6YHKN7M4V3CAQD63NXAU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'svgsalamander'
  package(s) announced via the FEDORA-2019-3cbce64a64 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "SVG Salamander is an SVG engine for Java that&#39, s designed to be small, fast,
and allow programmers to use it with a minimum of fuss. It&#39, s in particular
targeted for making it easy to integrate SVG into Java games and making it
much easier for artists to design 2D game content - from rich interactive
menus to charts and graphcs to complex animations." );
	script_tag( name: "affected", value: "'svgsalamander' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "svgsalamander", rpm: "svgsalamander~1.1.2~1.fc29", rls: "FC29" ) )){
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

