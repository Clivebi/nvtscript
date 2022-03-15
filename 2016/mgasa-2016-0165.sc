if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131287" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:17:50 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0165" );
	script_tag( name: "insight", value: "Updated quagga packages fix security vulnerability: A denial of dervice vulnerability have been found in BGP daemon from Quagga routing software (bgpd): if the following conditions are satisfied: - regular dumping is enabled - bgpd instance has many BGP peers then BGP message packets that are big enough cause bgpd to crash. The situation when the conditions above are satisfied is quite common. Moreover, it is easy to craft a packet which is much bigger than a typical packet, and hence such crafted packet can much more likely cause the crash (CVE-2016-4049)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0165.html" );
	script_cve_id( "CVE-2016-4049" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0165" );
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
	if(( res = isrpmvuln( pkg: "quagga", rpm: "quagga~0.99.22.4~4.2.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

