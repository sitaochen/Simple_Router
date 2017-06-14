UCLA CS118 Project 3 (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the [project description](http://web.cs.ucla.edu/classes/spring17/cs118/project-3.html).

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

### Group Information

    Name: Jia Hao
    UID: 904589119

### High Level Design of My Implementation

In `handlePacket()`, packet's headers are processed, and then packet is delivered to `processIncommingArp()`, `processIncommingIPv4()`, `processIncommingIcmp()` based on packet type. In each `processXXXX()` function, packet is further delivered to more specific subroutines.

Before sending an Arp packet, no need to consult ARP entries. Before sending an IP packet, first consult ARP entries. If arp entry not found, queue Request, else, create a new packet and send.

Once arp reply received, deliver queued Packet to `handlePacket()` again. 


### The problems I ran into and how I solved the problems

**Bug 1**: router program stuck by lock.
Cause: I put mutex lock inside `periodicCheckArpRequestsAndCacheEntries()`, while lock is already hold by `ticker()`.
Solution: remove mutex lock.

**Bug 2**: client ping 10.0.1.1 succeeded, but client ping other interfaces of router failed.
Cause: when router sends ICMP echo reply, the out interface was not set correctly. 
Solution: determine out interface by destination IP.

**Bug 3**: ICMP echo reply packet was not received by client.
Cause: data of ICMP was not used by checksum computing.

**Bug 4**: Routing table `lookup` returned incorrect entry.
Cause: When counting length of subnet mask, the mask is not converted as host byte order.

```c++
int len = 32;
unsigned rmask = ~ntohl(e.mask);
while (rmask > 0) {
    len --;
    rmask /= 2;
}
```

**Problem 1**: how to output debug info with least effort
Solution: I used preprocessor macros in `protocol.hpp`

```c++
#define DEBUG_ACTIVE
#ifdef DEBUG_ACTIVE
  #define PRINT_TOKEN(X) fprintf(stderr, "%s = %d\n", #X, X)
  #define PRINT_STR(str) fprintf(stderr, "%s = %s\n", #str, str)
  #define DEBUG printf("Function [%s] in LINE %d\n",__FUNCTION__,__LINE__)
  //#define DEBUG
  #define CERR(str) {std::cerr<<str<<std::endl;}
#else
  #define PRINT_TOKEN(X)  
  #define PRINT_STR(str)  
  #define DEBUG  
  #define CERR(str)  
#endif
```




### List of any additional libraries used

Acknowledgement of any online tutorials or code example (except class website) you have been using.

RFC of ICMP: https://tools.ietf.org/html/rfc792


