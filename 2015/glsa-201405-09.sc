if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121184" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:09 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201405-09" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in ImageMagick. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201405-09" );
	script_cve_id( "CVE-2012-1185", "CVE-2012-1186", "CVE-2012-0247", "CVE-2012-0248", "CVE-2013-4298", "CVE-2014-1947", "CVE-2014-2030" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201405-09" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "media-gfx/imagemagick", unaffected: make_list( "ge 6.8.8.10" ), vulnerable: make_list( "lt 6.8.8.10" ) ) ) != NULL){
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

