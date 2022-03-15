if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131182" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "creation_date", value: "2016-01-14 07:28:55 +0200 (Thu, 14 Jan 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0005" );
	script_tag( name: "insight", value: "This kernel update is based on upstream 4.1.15 longterm kernel and fixes various security issues." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0005.html" );
	script_cve_id( "CVE-2015-6937", "CVE-2015-7872", "CVE-2015-7884", "CVE-2015-7885", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8660" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-10 01:29:00 +0000 (Sun, 10 Sep 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0005" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.1.15~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-userspace-headers", rpm: "kernel-userspace-headers~4.1.15~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-xtables-addons", rpm: "kmod-xtables-addons~2.7~7.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-broadcom-wl", rpm: "kmod-broadcom-wl~6.30.223.271~4.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-fglrx", rpm: "kmod-fglrx~15.200.1046~8.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia304", rpm: "kmod-nvidia304~304.128~4.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia340", rpm: "kmod-nvidia340~340.93~4.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia-current", rpm: "kmod-nvidia-current~346.96~4.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

