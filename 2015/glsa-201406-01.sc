if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121204" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:17 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201406-01" );
	script_tag( name: "insight", value: "When libdbus is used in a setuid program, a user can gain escalated privileges by leveraging the DBUS_SYSTEM_BUS_ADDRESS variable. GLib can be used in a setuid context with D-Bus, and so can trigger this vulnerability. Please review the CVE identifier below for more details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201406-01" );
	script_cve_id( "CVE-2012-3524" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201406-01" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "sys-apps/dbus", unaffected: make_list( "ge 1.6.8" ), vulnerable: make_list( "lt 1.6.8" ) ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-libs/glib", unaffected: make_list( "ge 2.32.4-r1" ), vulnerable: make_list( "lt 2.32.4-r1" ) ) ) != NULL){
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
