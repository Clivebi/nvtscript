if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876512" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2016-1841", "CVE-2016-4607", "CVE-2016-4608", "CVE-2016-4610", "CVE-2016-4609", "CVE-2019-11068", "CVE-2016-1684", "CVE-2016-1683", "CVE-2016-4738" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 20:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-19 02:14:42 +0000 (Wed, 19 Jun 2019)" );
	script_name( "Fedora Update for mingw-libxslt FEDORA-2019-320d5295fc" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-320d5295fc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SK4YNISS22MJY22YX5I6V2U63QZAUEHA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-libxslt'
  package(s) announced via the FEDORA-2019-320d5295fc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This C library allows to transform XML files into other XML files
(or HTML, text, ...) using the standard XSLT stylesheet transformation
mechanism. To use it you need to have a version of libxml2 >= 2.6.27
installed. The xsltproc command is a command line interface to the XSLT engine" );
	script_tag( name: "affected", value: "'mingw-libxslt' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-libxslt", rpm: "mingw-libxslt~1.1.33~1.fc30", rls: "FC30" ) )){
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

