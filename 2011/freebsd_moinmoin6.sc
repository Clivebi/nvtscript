if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68816" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-0828" );
	script_bugtraq_id( 39110 );
	script_name( "FreeBSD Ports: moinmoin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: moinmoin

CVE-2010-0828
Cross-site scripting (XSS) vulnerability in action/Despam.py in the
Despam action module in MoinMoin 1.8.7 and 1.9.2 allows remote
authenticated users to inject arbitrary web script or HTML by creating
a page with a crafted URI." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://hg.moinmo.in/moin/1.9/raw-file/1.9.3/docs/CHANGES" );
	script_xref( name: "URL", value: "http://moinmo.in/MoinMoinBugs/1.9.2UnescapedInputForThemeAddMsg" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4c017345-1d89-11e0-bbee-0014a5e3cda6.html" );
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
bver = portver( pkg: "moinmoin" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.9.3" ) < 0){
	txt += "Package moinmoin version " + bver + " is installed which is known to be vulnerable.\n";
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

