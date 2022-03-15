if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68953" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "django -- multiple vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  py23-django
   py24-django
   py25-django
   py26-django
   py27-django
   py30-django
   py31-django
   py23-django-devel
   py24-django-devel
   py25-django-devel
   py26-django-devel
   py27-django-devel
   py30-django-devel
   py31-django-devel" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.djangoproject.com/weblog/2011/feb/08/security/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/bd760627-3493-11e0-8103-00215c6a37bb.html" );
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
bver = portver( pkg: "py23-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py23-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py23-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py24-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py24-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py24-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py25-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py25-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py25-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py26-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py26-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py26-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py27-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py27-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py27-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py30-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py30-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py30-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py31-django" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2" ) > 0 && revcomp( a: bver, b: "1.2.5" ) < 0){
	txt += "Package py31-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.1" ) > 0 && revcomp( a: bver, b: "1.1.4" ) < 0){
	txt += "Package py31-django version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py23-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py23-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py24-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py24-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py25-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py25-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py26-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py26-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py27-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py27-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py30-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py30-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "py31-django-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "15470,1" ) < 0){
	txt += "Package py31-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
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

