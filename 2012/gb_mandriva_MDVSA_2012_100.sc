if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:100" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831691" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-06-28 10:41:32 +0530 (Thu, 28 Jun 2012)" );
	script_cve_id( "CVE-2011-4623" );
	script_xref( name: "MDVSA", value: "2012:100" );
	script_name( "Mandriva Update for rsyslog MDVSA-2012:100 (rsyslog)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsyslog'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2010\\.1" );
	script_tag( name: "affected", value: "rsyslog on Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been discovered and corrected in rsyslog:

  An integer signedness error, leading to heap based buffer overflow
  was found in the way the imfile module of rsyslog, an enhanced
  system logging and kernel message trapping daemon, processed text
  files larger than 64 KB. When the imfile rsyslog module was enabled,
  a local attacker could use this flaw to cause denial of service
  (rsyslogd daemon hang) via specially-crafted message, to be logged
  (CVE-2011-4623).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "rsyslog", rpm: "rsyslog~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-dbi", rpm: "rsyslog-dbi~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-docs", rpm: "rsyslog-docs~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-gssapi", rpm: "rsyslog-gssapi~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-mysql", rpm: "rsyslog-mysql~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-pgsql", rpm: "rsyslog-pgsql~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-relp", rpm: "rsyslog-relp~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rsyslog-snmp", rpm: "rsyslog-snmp~4.6.2~3.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

