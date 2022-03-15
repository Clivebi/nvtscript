if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882715" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-16 06:52:26 +0200 (Tue, 16 May 2017)" );
	script_cve_id( "CVE-2017-8291" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ghostscript CESA-2017:1230 centos7" );
	script_tag( name: "summary", value: "Check the version of ghostscript" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Ghostscript suite contains utilities
for rendering PostScript and PDF documents. Ghostscript translates PostScript
code to common bitmap formats so that the code can be displayed or printed.


Security Fix(es):


  * It was found that ghostscript did not properly validate the parameters
passed to the .rsdparams and .eqproc functions. During its execution, a
specially crafted PostScript document could execute code in the context of
the ghostscript process, bypassing the -dSAFER protection. (CVE-2017-8291)" );
	script_tag( name: "affected", value: "ghostscript on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1230" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-May/022410.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.07~20.el7_3.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-cups", rpm: "ghostscript-cups~9.07~20.el7_3.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-devel", rpm: "ghostscript-devel~9.07~20.el7_3.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-doc", rpm: "ghostscript-doc~9.07~20.el7_3.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ghostscript-gtk", rpm: "ghostscript-gtk~9.07~20.el7_3.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

