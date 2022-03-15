if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71540" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037", "CVE-2012-2038", "CVE-2012-2039", "CVE-2012-2040" );
	script_version( "2020-08-18T09:42:52+0000" );
	script_tag( name: "last_modification", value: "2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: linux-f10-flashplugin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: linux-f10-flashplugin

CVE-2012-2034
Adobe Flash Player before 10.3.183.20 and 11.x before 11.3.300.257 on
Windows and Mac OS X, before 10.3.183.20 and 11.x before 11.2.202.236
on Linux, before 11.1.111.10 on Android 2.x and 3.x, and before
11.1.115.9 on Android 4.x, and Adobe AIR before 3.3.0.3610, allows
attackers to execute arbitrary code or cause a denial of service
(memory corruption) via unspecified vectors, a different vulnerability
than CVE-2012-2037.

CVE-2012-2035
Stack-based buffer overflow in Adobe Flash Player before 10.3.183.20
and 11.x before 11.3.300.257 on Windows and Mac OS X, before
10.3.183.20 and 11.x before 11.2.202.236 on Linux, before 11.1.111.10
on Android 2.x and 3.x, and before 11.1.115.9 on Android 4.x, and
Adobe AIR before 3.3.0.3610, allows attackers to execute arbitrary
code via unspecified vectors.

CVE-2012-2036
Integer overflow in Adobe Flash Player before 10.3.183.20 and 11.x
before 11.3.300.257 on Windows and Mac OS X, before 10.3.183.20 and
11.x before 11.2.202.236 on Linux, before 11.1.111.10 on Android 2.x
and 3.x, and before 11.1.115.9 on Android 4.x, and Adobe AIR before
3.3.0.3610, allows attackers to execute arbitrary code via unspecified
vectors.

CVE-2012-2037
Adobe Flash Player before 10.3.183.20 and 11.x before 11.3.300.257 on
Windows and Mac OS X, before 10.3.183.20 and 11.x before 11.2.202.236
on Linux, before 11.1.111.10 on Android 2.x and 3.x, and before
11.1.115.9 on Android 4.x, and Adobe AIR before 3.3.0.3610, allows
attackers to execute arbitrary code or cause a denial of service
(memory corruption) via unspecified vectors, a different vulnerability
than CVE-2012-2034.

CVE-2012-2038
Adobe Flash Player before 10.3.183.20 and 11.x before 11.3.300.257 on
Windows and Mac OS X, before 10.3.183.20 and 11.x before 11.2.202.236
on Linux, before 11.1.111.10 on Android 2.x and 3.x, and before
11.1.115.9 on Android 4.x, and Adobe AIR before 3.3.0.3610, allows
attackers to bypass intended access restrictions and obtain sensitive
information via unspecified vectors.

CVE-2012-2039
Adobe Flash Player before 10.3.183.20 and 11.x before 11.3.300.257 on
Windows and Mac OS X, before 10.3.183.20 and 11.x before 11.2.202.236
on Linux, before 11.1.111.10 on Android 2.x and 3.x, and before
11.1.115.9 on Android 4.x, and Adobe AIR before 3.3.0.3610, allows
attackers to execute arbitrary code or cause a denial of service (NULL
pointer dereference) via unspecified vectors.

CVE-2012-2040
Untrusted search path vulnerability in the installer in Adobe Flash
Player before 10.3.183.20 and 11.x before 11.3.300.257 on Windows and
Mac OS X, before 10.3.183.20 and 11.x before 11.2.202.236 on Linux,
before 11.1.111.10 on Android 2.x and 3.x, and before 11.1.115.9 on
Android 4.x, and Adobe AIR before 3.3.0.3610, allows local users to
gain privileges via a Trojan horse executable file in an unspecified
directory." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-14.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/38195f00-b215-11e1-8132-003067b2972c.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "linux-f10-flashplugin" );
if(!isnull( bver ) && revcomp( a: bver, b: "11.2r202.236" ) < 0){
	txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

