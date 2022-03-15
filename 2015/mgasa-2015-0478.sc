if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131158" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-12-18 06:57:26 +0200 (Fri, 18 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0478" );
	script_tag( name: "insight", value: "An unsafe use of string concatenation in a shell string occurs in FontManager. If the developer allows the attacker to choose the font and outputs an image, the attacker can execute any shell command on the remote system. The name variable injected comes from the constructor of FontManager, which is invoked by ImageFormatter from options (CVE-2015-8557, rhbz#1276321)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0478.html" );
	script_cve_id( "CVE-2015-8557" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0478" );
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
	if(( res = isrpmvuln( pkg: "python-pygments", rpm: "python-pygments~1.6~9.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

