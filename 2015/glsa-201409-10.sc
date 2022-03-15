if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121273" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:55 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201409-10" );
	script_tag( name: "insight", value: "Stephane Chazelas reported that Bash incorrectly handles function definitions, allowing attackers to inject arbitrary code (CVE-2014-6271). Gentoo Linux informed about this issue in GLSA 201409-09." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201409-10" );
	script_cve_id( "CVE-2014-6271", "CVE-2014-7169" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201409-10" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 3.1_p18-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 3.2_p52-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 4.0_p39-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 4.1_p12-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list( "ge 4.2_p48-r1" ), vulnerable: make_list() ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "app-shells/bash", unaffected: make_list(), vulnerable: make_list( "lt 4.2_p48-r1" ) ) ) != NULL){
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

