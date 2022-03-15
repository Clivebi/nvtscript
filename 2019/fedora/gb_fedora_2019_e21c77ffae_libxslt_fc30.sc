if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876493" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-11068" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-14 02:10:28 +0000 (Fri, 14 Jun 2019)" );
	script_name( "Fedora Update for libxslt FEDORA-2019-e21c77ffae" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-e21c77ffae" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/36TEYN37XCCKN2XUMRTBBW67BPNMSW4K" );
	script_tag( name: "summary", value: "The remote host is missing an update
  for the 'libxslt' package(s) announced via the FEDORA-2019-e21c77ffae advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "This C library allows to transform XML files
  into other XML files (or HTML, text, ...) using the standard XSLT stylesheet
  transformation mechanism. To use it you need to have a version of libxml2 >= 2.6.27
  installed. The xsltproc command is a command line interface to the XSLT engine" );
	script_tag( name: "affected", value: "'libxslt' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "libxslt", rpm: "libxslt~1.1.33~1.fc30", rls: "FC30" ) )){
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

