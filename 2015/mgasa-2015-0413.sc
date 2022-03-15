if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131100" );
	script_version( "2020-06-23T09:25:46+0000" );
	script_tag( name: "creation_date", value: "2015-10-26 09:35:58 +0200 (Mon, 26 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-06-23 09:25:46 +0000 (Tue, 23 Jun 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0413" );
	script_tag( name: "insight", value: "It was found that ntpd did not correctly implement the threshold limitation for the '-g' option, which is used to set the time without any restrictions. A man-in-the-middle attacker able to intercept NTP traffic between a connecting client and an NTP server could use this flaw to force that client to make multiple steps larger than the panic threshold, effectively changing the time to an arbitrary value at any time (CVE-2015-5300). Slow memory leak in CRYPTO_ASSOC with autokey (CVE-2015-7701). Incomplete autokey data packet length checks could result in crash caused by a crafted packet (CVE-2015-7691, CVE-2015-7692, CVE-2015-7702). Clients that receive a KoD should validate the origin timestamp field (CVE-2015-7704). ntpq atoascii() Memory Corruption Vulnerability could result in ntpd crash caused by a crafted packet (CVE-2015-7852). Symmetric association authentication bypass via crypto-NAK (CVE-2015-7871)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0413.html" );
	script_cve_id( "CVE-2015-5300", "CVE-2015-7701", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7871" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0413" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~24.2.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

