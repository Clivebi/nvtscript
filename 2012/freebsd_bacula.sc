if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72197" );
	script_cve_id( "CVE-2012-4430" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:25:48 -0400 (Sat, 15 Sep 2012)" );
	script_name( "FreeBSD Ports: bacula" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bacula" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.bacula.org/git/cgit.cgi/bacula/commit/?id=67debcecd3d530c429e817e1d778e79dcd1db905" );
	script_xref( name: "URL", value: "https://secunia.com/advisories/50535/" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/bacula/files/bacula/5.2.11/ReleaseNotes/view" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/143f6932-fedb-11e1-ad4a-003067b2972c.html" );
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
bver = portver( pkg: "bacula" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2.11" ) < 0){
	txt += "Package bacula version " + bver + " is installed which is known to be vulnerable.\\n";
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

