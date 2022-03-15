if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121443" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-08 07:14:12 +0200 (Tue, 08 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201603-01" );
	script_tag( name: "insight", value: "GIMPs network server, scriptfu, is vulnerable to the remote execution of arbitrary code via the python-fu-eval command due to not requiring authentication. Additionally, the X Window Dump (XWD) plugin is vulnerable to multiple buffer overflows possibly allowing the remote execution of arbitrary code or Denial of Service. The XWD plugin is vulnerable due to not validating large color entries." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201603-01" );
	script_cve_id( "CVE-2012-4245", "CVE-2013-1913", "CVE-2013-1978" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201603-01" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "media-gfx/gimp", unaffected: make_list( "ge 2.8.0" ), vulnerable: make_list( "lt 2.8.0" ) ) ) != NULL){
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

