if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.57174" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_name( "Slackware Advisory SSA:2006-200-01 Samba 2.0.23 repackaged" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.0|10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-200-01" );
	script_tag( name: "insight", value: "New Samba packages are available for Slackware 10.0, 10.1, 10.2,
and -current.

In Slackware 10.0, 10.1, and 10.2, Samba was evidently picking up
the libdm.so.0 library causing a Samba package issued primarily as
a security patch to suddenly require a library that would only be
present on the machine if the xfsprogs package (from the A series
but marked 'optional') was installed.  Sorry -- this was not
intentional, though I do know that I'm taking the chance of this
kind of issue when trying to get security related problems fixed
quickly (hopefully balanced with reasonable testing), and when the
fix is achieved by upgrading to a new version rather than with the
smallest patch possible to fix the known issue.  However, I tend
to trust that by following upstream sources as much as possible
I'm also fixing some problems that aren't yet public.

So, all of the 10.0, 10.1, and 10.2 packages have been rebuilt
on systems without the dm library, and should be able to directly
upgrade older samba packages without additional requirements.
Well, unless they are also under /patches.

All the packages (including -current) have been patched with a
fix from Samba's CVS for some reported problems with winbind.
Thanks to Mikhail Kshevetskiy for pointing me to the patch.

I realize these packages don't really fix security issues, but
they do fix security patch packages that are less than a couple
of days old, so it seems prudent to notify slackware-security
(and any subscribed lists) again. Sorry if it's noise." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-200-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "samba", ver: "3.0.23-i486-2_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "samba", ver: "3.0.23-i486-2_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "samba", ver: "3.0.23-i486-2_slack10.2", rls: "SLK10.2" ) ) != NULL){
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

