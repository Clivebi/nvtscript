if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131246" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-03 14:39:16 +0200 (Thu, 03 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0091" );
	script_tag( name: "insight", value: "Updated wireshark packages fix security vulnerabilities: ASN.1 BER dissector crash (CVE-2016-2522). DNP dissector infinite loop (CVE-2016-2523). X.509AF dissector crash (CVE-2016-2524). HTTP/2 dissector crash (CVE-2016-2525). HiQnet dissector crash (CVE-2016-2526). 3GPP TS 32.423 Trace file parser crash (CVE-2016-2527). LBMC dissector crash (CVE-2016-2528). iSeries file parser crash (CVE-2016-2529). RSL dissector crash (CVE-2016-2530, CVE-2016-2531). LLRP dissector crash (CVE-2016-2532). The wireshark package has been updated to version 2.0.2, fixing these issues as well as other dissector crashes, a dissector loop issue, another file parser crash, and several other bugs. See the upstream release notes for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0091.html" );
	script_cve_id( "CVE-2016-2522", "CVE-2016-2523", "CVE-2016-2524", "CVE-2016-2525", "CVE-2016-2526", "CVE-2016-2527", "CVE-2016-2528", "CVE-2016-2529", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0091" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~2.0.2~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

