# schadnfreude

You'll be happy they can't spy on you. 

🔒 🕵 👨‍👩‍👧‍👦 📞 🎥 📂 🖧 🛡

An end-to-end encrypted, anonymous IP-hiding, decentralized, audio/video/file sharing/offline messaging multi-device platform built for both communications and application security and performance.

    Secure
    Communications
    Hopping:
    Anonymous
    Delivery.
    Now
    For
    Relaxing,
    Enjoy
    Undercover
    Digital
    Excellence

## Goal

Schadnfreude's goal is to provide all the advantages of a traditional secure messaging platform without the pitfalls of centrally-controlled services and vulnerable technologies. Specifically, we seek to anonymize endpoints, hide IP addresses, prevent user enumeration, eliminate single points of failure, and categorically prevent the most common and severe vulnerability classes, while preserving the performance, convienience, and features of other secure messaging applications.

## Implementation

Schadnfreude uses a network of nodes to perform its anonymizing functionality. The schadnfreude client selects one or more meet nodes to use long-term, but may change it later if desired. The meet node holds offline encrypted messages and files, but cannot read them or see who is accessing them. The schadnfreude client never connects directly to its meet node, instead setting up tunnels through one or more relay nodes first. Likewise, relays are used to connect to other clients' meet nodes as well.

Schadnfreude uses a message-based model riding over UDP by default for maximum performance. This allows it to reduce round trip times combining cryptographic and traditional connection initiation, and better support realtime audio/video communications, allowing packet drops. Connection metadata is authenticated, which allows us to better resist man-on-the-side attackers seeking to cause a denial of service among other threats.

Contacts are identified by public key. Such keys are used when setting up a conversation, which establishes a symmetric key to authenticate and encrypt messages between two endpoints. This key may be shared later with additional contacts to invite them to the conversation and enable them to see the group messages.

## Comparison

Other applications like Signal, WhatsApp, and Telegram are only built to protect message contents from third parties. They each use a centrally-controlled set of servers that can see the metadata (who sends and receives messages, when, and how big they are) as well as even the contact lists of their users. Such information includes real phone numbers and IP addresses of users, which are tied strongly to their real-world identities, making such messengers a very bad choice for users who need to conceal their identities while communicating.

Much of this information, such as IP addresses, is visible to not only the central servers but also the cloud providers they run on, the ISP's they use, and since those mobile messengers use Google Cloud Messaging and Apple Push Notification Service to notify your phones, metadata about messages including the real recipient identity is also visible to Google and Apple. In each of those apps, by default the user's IP address is also directly revealed to anyone they voice or video call. Even if one of those entities promises not to retain this information, nothing prevents the others from doing so, or the first from being compelled to at some point in the future.

Metadata exposes enormous amounts of sensitive personal information everyone should be concerned about revealing. In [Why Metadata Matters](https://www.eff.org/deeplinks/2013/06/why-metadata-matters) the EFF illustrated how metadata provides enough context to know some of the most intimate details of your lives.

In addition, the users are at the mercy of a centrally-controlled server and application ecosystem and are vulnerable to service disruption from many sources.

Not so with Schadnfreude.

Schadnfreude's relaying hides IP addresses, meet nodes avoid single point of failure and tracking, and public key based chats and key derivations avoid identity tracking, even by the meet nodes. This also prevents user/endpoint enumeration and spamming that has happened in earlier anonymity networks or phone number-based secure chat systems.

## license

`schadnfreude` is licensed under both the Apache2 and MIT licenses. Unlike other messaging services, this includes both client and server code.
