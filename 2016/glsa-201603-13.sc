if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121455" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-14 15:52:48 +0200 (Mon, 14 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201603-13" );
	script_tag( name: "insight", value: "The pluto IKE daemon in Libreswan, when built with NSS, allows remote attackers to cause a Denial of Service (assertion failure and daemon restart) via a zero DH g^x value in a KE payload in a IKE packet. Additionally, remote attackers could cause a Denial of Service (daemon restart) via an IKEv1 packet with (1) unassigned bits set in the IPSEC DOI value or (2) the next payload value set to ISAKMP_NEXT_SAK." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201603-13" );
	script_cve_id( "CVE-2015-3204", "CVE-2015-3240" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "net-misc/libreswan", unaffected: make_list( "ge 3.15" ), vulnerable: make_list( "lt 3.15" ) ) ) != NULL){
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

