if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71372" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-2369" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)" );
	script_name( "FreeBSD Ports: pidgin-otr" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: pidgin-otr

CVE-2012-2369
Format string vulnerability in the log_message_cb function in
otr-plugin.c in the Off-the-Record Messaging (OTR) pidgin-otr plugin
before 3.2.1 for Pidgin might allow remote attackers to execute
arbitrary code via format string specifiers in data that generates a
log message." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.cypherpunks.ca/otr/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/aa71daaa-9f8c-11e1-bd0a-0082a0c18826.html" );
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
bver = portver( pkg: "pidgin-otr" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.2.1" ) < 0){
	txt += "Package pidgin-otr version " + bver + " is installed which is known to be vulnerable.\\n";
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

