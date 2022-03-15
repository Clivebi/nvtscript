if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-September/msg00001.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870698" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-07-09 10:50:25 +0530 (Mon, 09 Jul 2012)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "RHSA", value: "2011:1248-01" );
	script_name( "RedHat Update for ca-certificates RHSA-2011:1248-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ca-certificates'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "ca-certificates on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "This package contains the set of CA certificates chosen by the Mozilla
  Foundation for use with the Internet Public Key Infrastructure (PKI).

  It was found that a Certificate Authority (CA) issued fraudulent HTTPS
  certificates. This update removes that CA's root certificate from the
  ca-certificates package, rendering any HTTPS certificates signed by that CA
  as untrusted. (BZ#734381)

  All users should upgrade to this updated package. After installing the
  update, all applications using the ca-certificates package must be
  restarted for the changes to take effect." );
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "ca-certificates", rpm: "ca-certificates~2010.63~3.el6_1.5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

