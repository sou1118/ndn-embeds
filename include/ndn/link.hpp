/**
 * @file link.hpp
 * @brief NDN Link Object
 *
 * A Link Object is a special Data packet containing a list of Names
 * (delegations) used as ForwardingHints.
 *
 * @see https://docs.named-data.net/NDN-packet-spec/current/link.html
 */

#pragma once

#include "ndn/common.hpp"
#include "ndn/data.hpp"
#include "ndn/name.hpp"

namespace ndn {

/**
 * @brief NDN Link Object
 *
 * A Link Object is a special Data packet with ContentType=LINK,
 * containing one or more Names (delegations) in its Content field.
 * Provides a list of Names sorted by producer priority.
 *
 * @code
 * // Create a Link
 * ndn::Link link;
 * link.setName("/example/link");
 * link.addDelegation("/ndn/jp/provider1");
 * link.addDelegation("/ndn/us/provider2");
 *
 * // Encode to Data
 * ndn::Data data = link.toData();
 * data.signWithDigestSha256();
 *
 * // Decode
 * auto result = ndn::Link::fromData(data);
 * if (result.ok()) {
 *     for (size_t i = 0; i < result.value.delegationCount(); ++i) {
 *         auto delegation = result.value.delegation(i);
 *         if (delegation) {
 *             // Use delegation->toUri(...)
 *         }
 *     }
 * }
 * @endcode
 */
class Link {
public:
    /**
     * @brief Default constructor
     *
     * Creates an empty Link.
     */
    Link() = default;

    /**
     * @brief Create a Link with a specified Name
     * @param name The Link name
     */
    explicit Link(const Name& name);

    /** @name Delegation management
     * @{
     */

    /**
     * @brief Add a delegation (Name)
     *
     * Add in order of producer priority.
     * The first added has the highest priority.
     *
     * @param delegation Name to add
     * @return Error::Success on success, Error::Full when at capacity, Error::InvalidParam on
     * duplicate
     */
    Error addDelegation(const Name& delegation);

    /**
     * @brief Add a delegation from a URI string
     * @param uri URI string (e.g., "/ndn/jp/provider")
     * @return Error::Success on success
     */
    Error addDelegation(std::string_view uri);

    /**
     * @brief Get the number of delegations
     * @return Number of delegations
     */
    size_t delegationCount() const { return delegationCount_; }

    /**
     * @brief Get a delegation by index
     *
     * @param index Delegation index (starting from 0)
     * @return Pointer to the Name at the given index, nullptr if out of range
     */
    const Name* delegation(size_t index) const;

    /**
     * @brief Clear all delegations
     */
    void clearDelegations();

    /**
     * @brief Check if a given Name is in the delegation list
     * @param name Name to check
     * @return true if present
     */
    bool hasDelegation(const Name& name) const;
    /** @} */

    /** @name Name access
     * @{
     */

    /**
     * @brief Get the Name (const reference)
     * @return Const reference to the Name
     */
    const Name& name() const { return name_; }

    /**
     * @brief Get the Name (reference)
     * @return Reference to the Name
     */
    Name& name() { return name_; }

    /**
     * @brief Set the Name
     * @param name Name to set
     * @return Reference to this Link
     */
    Link& setName(const Name& name);

    /**
     * @brief Set the Name from a URI string
     * @param uri URI string
     * @return Error::Success on success
     */
    Error setName(std::string_view uri);
    /** @} */

    /** @name Conversion to Data
     * @{
     */

    /**
     * @brief Convert the Link to a Data packet
     *
     * Generates a Data packet with ContentType=LINK.
     * The Content contains the encoded delegations (list of Names).
     * Signing is not performed by this method.
     *
     * @param data Output Data
     * @return Error::Success on success
     */
    Error toData(Data& data) const;

    /**
     * @brief Decode a Link from a Data packet
     *
     * Extracts the delegation list from a Data with ContentType=LINK.
     *
     * @param data Input Data
     * @return Link and Error::Success on success, Error::InvalidPacket if not a Link
     */
    static Result<Link> fromData(const Data& data);
    /** @} */

private:
    Name name_;                                           ///< Link name
    std::array<Name, LINK_MAX_DELEGATIONS> delegations_;  ///< Delegation list
    size_t delegationCount_ = 0;                          ///< Delegation count
};

}  // namespace ndn
