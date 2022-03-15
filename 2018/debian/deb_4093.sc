if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704093" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2018-5704" );
	script_name( "Debian Security Advisory DSA 4093-1 (openocd - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-21 00:00:00 +0100 (Sun, 21 Jan 2018)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-09 17:55:00 +0000 (Fri, 09 Feb 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4093.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "openocd on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 0.8.0-4+deb7u1.

For the stable distribution (stretch), this problem has been fixed in
version 0.9.0-1+deb8u1.

We recommend that you upgrade your openocd packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openocd" );
	script_tag( name: "summary", value: "Josef Gajdusek discovered that OpenOCD, a JTAG debugger for ARM and MIPS,
was vulnerable to Cross Protocol Scripting attacks. An attacker could
craft a HTML page that, when visited by a victim running OpenOCD, could
execute arbitrary commands on the victims host.

This fix also sets the OpenOCD default binding to localhost, instead of
every network interfaces. This can be changed with the added bindto

command argument." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openocd", ver: "0.8.0-4+deb7u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openocd", ver: "0.9.0-1+deb8u1", rls: "DEB9" ) )){
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

