if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882135" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-27 06:53:58 +0100 (Fri, 27 Mar 2015)" );
	script_cve_id( "CVE-2015-1815" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for setroubleshoot CESA-2015:0729 centos5" );
	script_tag( name: "summary", value: "Check the version of setroubleshoot" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an alert
can be generated that provides information about the problem and helps to
track its resolution.

It was found that setroubleshoot did not sanitize file names supplied in a
shell command look-up for RPMs associated with access violation reports.
An attacker could use this flaw to escalate their privileges on the system
by supplying a specially crafted file to the underlying shell command.
(CVE-2015-1815)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
reporting this issue.

All setroubleshoot users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "setroubleshoot on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:0729" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-March/020999.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "setroubleshoot", rpm: "setroubleshoot~2.0.5~7.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "setroubleshoot-server", rpm: "setroubleshoot-server~2.0.5~7.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

