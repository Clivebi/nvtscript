if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871023" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-05-20 12:45:12 +0530 (Tue, 20 May 2014)" );
	script_cve_id( "CVE-2013-4073" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "RedHat Update for ruby RHSA-2013:1090-01" );
	script_tag( name: "affected", value: "ruby on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "Ruby is an extensible, interpreted, object-oriented, scripting language.
It has features to process text files and to do system management tasks.

A flaw was found in Ruby's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. An attacker
could potentially exploit this flaw to conduct man-in-the-middle attacks to
spoof SSL servers. Note that to exploit this issue, an attacker would need
to obtain a carefully-crafted certificate signed by an authority that the
client trusts. (CVE-2013-4073)

All users of Ruby are advised to upgrade to these updated packages, which
contain backported patches to resolve this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2013:1090-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-July/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(6|5)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-debuginfo", rpm: "ruby-debuginfo~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-devel", rpm: "ruby-devel~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-irb", rpm: "ruby-irb~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-libs", rpm: "ruby-libs~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-rdoc", rpm: "ruby-rdoc~1.8.7.352~12.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-debuginfo", rpm: "ruby-debuginfo~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-devel", rpm: "ruby-devel~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-docs", rpm: "ruby-docs~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-irb", rpm: "ruby-irb~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-libs", rpm: "ruby-libs~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-mode", rpm: "ruby-mode~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-rdoc", rpm: "ruby-rdoc~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-ri", rpm: "ruby-ri~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ruby-tcltk", rpm: "ruby-tcltk~1.8.5~31.el5_9", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

