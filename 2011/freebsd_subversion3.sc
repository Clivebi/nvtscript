if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69146" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-0715" );
	script_name( "FreeBSD Ports: subversion" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  subversion
   subversion-freebsd" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
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
bver = portver( pkg: "subversion" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6" ) >= 0 && revcomp( a: bver, b: "1.6.15" ) <= 0){
	txt += "Package subversion version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.6.9" ) <= 0){
	txt += "Package subversion version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "subversion-freebsd" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6" ) >= 0 && revcomp( a: bver, b: "1.6.15" ) <= 0){
	txt += "Package subversion-freebsd version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.6.9" ) <= 0){
	txt += "Package subversion-freebsd version " + bver + " is installed which is known to be vulnerable.\n";
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

